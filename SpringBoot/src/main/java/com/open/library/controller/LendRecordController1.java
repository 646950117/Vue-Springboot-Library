package com.open.library.controller;

import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.open.library.commom.Result;
import com.open.library.entity.LendRecord;
import com.open.library.mapper.LendRecordMapper;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

@RestController
@RequestMapping("/LendRecord1")
public class LendRecordController1 {
    @Resource
    LendRecordMapper LendRecordMapper;
    @PutMapping
    public  Result<?> update2( @RequestBody LendRecord lendRecord){
        UpdateWrapper<LendRecord> updateWrapper = new UpdateWrapper<>();
        updateWrapper.eq("isbn",lendRecord.getIsbn()).eq("reader_id",lendRecord.getReaderId()).eq("borrownum",lendRecord.getBorrownum());
        LendRecord lendrecord = new LendRecord();
        lendrecord.setReturnTime(lendRecord.getReturnTime());
        lendrecord.setStatus(lendRecord.getStatus());
        LendRecordMapper.update(lendrecord, updateWrapper);
        return Result.success();
    }



}
